import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ShieldAlert,
  Activity,
  ShieldCheck,
  Flame,
  Radio,
  ArrowUpRight,
  Lock,
  Search,
  Filter,
  Sliders,
  ChevronDown,
  X,
  Gauge,
  Layers,
  Sparkles
} from 'lucide-react';
import { SecurityAuditLog } from '../types.ts';
import { useTheme } from '../context/ThemeContext.tsx';

interface ThreatSummaryCardProps {
  logs: SecurityAuditLog[];
}

export const ThreatSummaryCard: React.FC<ThreatSummaryCardProps> = ({ logs }) => {
  const { isLight } = useTheme();
  const [filterMode, setFilterMode] = useState<'ALL' | 'CRITICAL' | 'SUSPICIOUS' | 'NOMINAL'>('ALL');
  const [threatSearch, setThreatSearch] = useState('');
  const [selectedPrincipal, setSelectedPrincipal] = useState<string>('ALL');

  const {
    criticalBlocks,
    criticalCount,
    avgThreatLevel,
    avgCriticalRisk,
    threatCondition,
    recentCritical,
    affectedPrincipals,
    totalBlocks
  } = useMemo(() => {
    // Critical audit blocks: risk > 75 and BLOCKED
    const critical = logs.filter((l) => l.calculated_risk >= 75 && l.status === 'BLOCKED');
    const allBlocks = logs.filter((l) => l.status === 'BLOCKED');

    // Average threat level across all evaluated requests
    const avgOverall = logs.length > 0
      ? Math.round(logs.reduce((sum, l) => sum + l.calculated_risk, 0) / logs.length)
      : 0;

    // Average risk among critical blocks
    const avgCrit = critical.length > 0
      ? Math.round(critical.reduce((sum, l) => sum + l.calculated_risk, 0) / critical.length)
      : 0;

    // Threat condition classification
    let condition: { label: string; color: string; bg: string; border: string; icon: typeof ShieldCheck } = {
      label: 'NOMINAL DEFENSE',
      color: 'text-emerald-400',
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/30',
      icon: ShieldCheck
    };

    if (critical.length >= 3 || avgOverall >= 60) {
      condition = {
        label: 'CRITICAL THREAT DEFCON 1',
        color: 'text-rose-400',
        bg: 'bg-rose-500/15',
        border: 'border-rose-500/30',
        icon: ShieldAlert
      };
    } else if (critical.length > 0 || avgOverall >= 30) {
      condition = {
        label: 'ELEVATED MITIGATION',
        color: 'text-amber-400',
        bg: 'bg-amber-400/15',
        border: 'border-amber-400/30',
        icon: AlertTriangle
      };
    }

    // Most recent critical block
    const latest = critical[0] || null;

    // Unique affected principals
    const principals = Array.from(new Set(critical.map((l) => l.username)));

    return {
      criticalBlocks: critical,
      criticalCount: critical.length,
      avgThreatLevel: avgOverall,
      avgCriticalRisk: avgCrit,
      threatCondition: condition,
      recentCritical: latest,
      affectedPrincipals: principals,
      totalBlocks: allBlocks.length
    };
  }, [logs]);

  // Filtered threat events for the embedded inspector
  const filteredThreatEvents = useMemo(() => {
    return logs.filter((l) => {
      // Filter mode
      if (filterMode === 'CRITICAL' && l.calculated_risk < 75) return false;
      if (filterMode === 'SUSPICIOUS' && (l.calculated_risk < 30 || l.calculated_risk >= 75)) return false;
      if (filterMode === 'NOMINAL' && l.calculated_risk >= 30) return false;

      // Principal filter
      if (selectedPrincipal !== 'ALL' && l.username !== selectedPrincipal) return false;

      // Search text
      if (threatSearch.trim()) {
        const q = threatSearch.toLowerCase();
        const matchesUser = l.username.toLowerCase().includes(q);
        const matchesFn = l.requested_function.toLowerCase().includes(q);
        const matchesReason = l.reason.toLowerCase().includes(q);
        if (!matchesUser && !matchesFn && !matchesReason) return false;
      }

      return true;
    });
  }, [logs, filterMode, selectedPrincipal, threatSearch]);

  const StatusIcon = threatCondition.icon;

  // Calculate SVG arc strokeDashoffset for circular risk dial
  const gaugeRadius = 38;
  const gaugeCircumference = 2 * Math.PI * gaugeRadius;
  // Use half-circle (180 deg) or 3/4 circle
  const dashoffset = gaugeCircumference - (Math.min(avgThreatLevel, 100) / 100) * (gaugeCircumference * 0.75);

  return (
    <section
      id="threat-summary-card"
      aria-label="Real-time Threat Summary"
      className="glossy-panel p-5 rounded-2xl font-mono relative overflow-hidden transition-colors duration-200"
    >
      {/* Decorative top accent line reflecting threat level */}
      <div
        className={`absolute top-0 left-0 right-0 h-[2px] transition-colors duration-500 ${
          criticalCount > 0 ? 'bg-rose-500' : avgThreatLevel > 20 ? 'bg-amber-400' : 'bg-blue-500'
        }`}
      />

      {/* Header bar */}
      <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 mb-4 border-b ${
        isLight ? 'border-slate-200' : 'border-slate-800/80'
      }`}>
        <div className="flex items-center gap-2.5">
          <div className={`p-2 rounded-xl border ${threatCondition.bg} ${threatCondition.border} ${threatCondition.color}`}>
            <StatusIcon className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className={`text-sm font-bold uppercase tracking-wider ${isLight ? 'text-slate-900' : 'text-white'}`}>
                Real-Time Threat Intelligence &amp; Risk Visualizer
              </h2>
              <span className={`flex items-center gap-1 text-[10px] ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
                <Radio className="w-3 h-3 text-blue-500 animate-pulse" />
                Live Heuristics
              </span>
            </div>
            <p className={`text-[11px] mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
              Continuous telemetry aggregation of high-risk security incidents and Markov sequence threat scores
            </p>
          </div>
        </div>

        {/* Global Threat Condition Badge */}
        <div
          id="threat-condition-badge"
          className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-xl text-xs font-bold uppercase tracking-wider border self-start sm:self-auto shadow-xs ${threatCondition.bg} ${threatCondition.border} ${threatCondition.color}`}
        >
          <span className="w-2 h-2 rounded-full bg-current animate-ping" />
          <span>{threatCondition.label}</span>
        </div>
      </div>

      {/* Core Metrics & Visual Risk Radial Meter Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5 mb-5">
        {/* Metric 1: Visual Radial Threat Dial */}
        <div className={`glossy-panel glossy-card-hover p-3.5 rounded-2xl flex items-center justify-between gap-2 sm:col-span-2 lg:col-span-1 shadow-xs`}>
          <div className="relative w-18 h-18 shrink-0 flex items-center justify-center">
            <svg className="w-18 h-18 -rotate-90 transform" viewBox="0 0 90 90">
              {/* Background circle */}
              <circle
                cx="45"
                cy="45"
                r={gaugeRadius}
                stroke={isLight ? '#e2e8f0' : '#1e293b'}
                strokeWidth="7"
                fill="none"
              />
              {/* Foreground progress arc */}
              <circle
                cx="45"
                cy="45"
                r={gaugeRadius}
                stroke={
                  avgThreatLevel >= 75
                    ? (isLight ? '#e11d48' : '#ff4a6b')
                    : avgThreatLevel >= 50
                    ? (isLight ? '#d97706' : '#f59e0b')
                    : avgThreatLevel >= 25
                    ? (isLight ? '#0284c7' : '#00d2ff')
                    : (isLight ? '#059669' : '#00ff87')
                }
                strokeWidth="7"
                strokeDasharray={gaugeCircumference}
                strokeDashoffset={dashoffset}
                strokeLinecap="round"
                fill="none"
                className="transition-all duration-700 ease-out"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span
                className={`text-base font-extrabold ${
                  avgThreatLevel >= 75
                    ? (isLight ? 'text-rose-700' : 'text-rose-400')
                    : avgThreatLevel >= 50
                    ? (isLight ? 'text-amber-800' : 'text-amber-400')
                    : avgThreatLevel >= 25
                    ? (isLight ? 'text-sky-700' : 'text-cyan-400')
                    : (isLight ? 'text-emerald-700' : 'text-emerald-400')
                }`}
              >
                {avgThreatLevel}%
              </span>
            </div>
          </div>

          <div className="flex-1 min-w-0">
            <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase font-semibold block">
              Threat Dial
            </span>
            <strong className={`text-xs block truncate mt-0.5 ${isLight ? 'text-slate-900 font-bold' : 'text-white'}`}>
              {avgThreatLevel >= 75
                ? 'DEFCON 1 (CRITICAL)'
                : avgThreatLevel >= 50
                ? 'DEFCON 2 (ELEVATED)'
                : avgThreatLevel >= 25
                ? 'DEFCON 3 (GUARDED)'
                : 'DEFCON 5 (NOMINAL)'}
            </strong>
            <span className="text-[9px] text-slate-400 dark:text-slate-500 block mt-0.5">
              Across {logs.length} events
            </span>
          </div>
        </div>

        {/* Metric 2: Critical Blocks (Risk > 75) */}
        <div
          id="metric-critical-blocks"
          className="glossy-panel glossy-card-hover p-3.5 rounded-2xl flex flex-col justify-between shadow-xs"
        >
          <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">
            <span>Critical Blocks (&ge;75%)</span>
            <ShieldAlert className="w-4 h-4 text-rose-500" />
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className={`text-2xl font-extrabold ${criticalCount > 0 ? 'text-rose-500' : isLight ? 'text-slate-900' : 'text-white'}`}>
              {criticalCount}
            </span>
            <span className="text-[11px] text-slate-500 dark:text-slate-400">
              of {totalBlocks} total blocked
            </span>
          </div>
          <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-1 flex items-center justify-between">
            <span>Cutoff: 75%</span>
            <span className={criticalCount > 0 ? 'text-rose-500 font-bold' : 'text-emerald-500 font-semibold'}>
              {criticalCount > 0 ? 'INTERCEPTED' : 'CLEAR'}
            </span>
          </div>
        </div>

        {/* Metric 3: Average Threat Level */}
        <div
          id="metric-avg-threat"
          className="glossy-panel glossy-card-hover p-3.5 rounded-2xl flex flex-col justify-between shadow-xs"
        >
          <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">
            <span>Average Threat</span>
            <Flame className={`w-4 h-4 ${avgThreatLevel >= 75 ? 'text-rose-500' : avgThreatLevel >= 30 ? 'text-amber-500' : 'text-emerald-500'}`} />
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span
              className={`text-2xl font-extrabold ${
                avgThreatLevel >= 75
                  ? 'text-rose-500'
                  : avgThreatLevel >= 30
                  ? 'text-amber-500'
                  : isLight ? 'text-emerald-600' : 'text-emerald-400'
              }`}
            >
              {avgThreatLevel}%
            </span>
            <span className="text-[11px] text-slate-500 dark:text-slate-400">
              {logs.length} evaluated
            </span>
          </div>
          <div className="w-full bg-slate-200 dark:bg-slate-900 h-1.5 rounded-full overflow-hidden mt-1.5 border border-slate-300 dark:border-slate-800">
            <div
              className={`h-full transition-all duration-300 ${
                avgThreatLevel >= 75
                  ? 'bg-rose-500'
                  : avgThreatLevel >= 30
                  ? 'bg-amber-400'
                  : 'bg-emerald-500'
              }`}
              style={{ width: `${Math.min(avgThreatLevel, 100)}%` }}
            />
          </div>
        </div>

        {/* Metric 4: Critical Mean Severity */}
        <div
          id="metric-crit-severity"
          className="glossy-panel glossy-card-hover p-3.5 rounded-2xl flex flex-col justify-between shadow-xs"
        >
          <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">
            <span>Mean Crit Severity</span>
            <Activity className="w-4 h-4 text-blue-500" />
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className={`text-2xl font-extrabold ${isLight ? 'text-slate-900' : 'text-white'}`}>
              {avgCriticalRisk > 0 ? `${avgCriticalRisk}%` : '0%'}
            </span>
            <span className="text-[11px] text-slate-500 dark:text-slate-400">
              when blocked
            </span>
          </div>
          <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-1 flex items-center justify-between">
            <span>Penalty: +40%</span>
            <span>RBAC: 90%</span>
          </div>
        </div>

        {/* Metric 5: Intercepted Principals */}
        <div
          id="metric-affected-principals"
          className="glossy-panel glossy-card-hover p-3.5 rounded-2xl flex flex-col justify-between shadow-xs"
        >
          <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400 uppercase font-semibold">
            <span>Flagged Principals</span>
            <Lock className="w-4 h-4 text-purple-500" />
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className={`text-2xl font-extrabold ${isLight ? 'text-slate-900' : 'text-white'}`}>
              {affectedPrincipals.length}
            </span>
            <span className="text-[11px] text-slate-500 dark:text-slate-400">
              identities
            </span>
          </div>
          <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-1 truncate">
            {affectedPrincipals.length > 0 ? (
              <span className="text-rose-500 font-bold">
                {affectedPrincipals.join(', ')}
              </span>
            ) : (
              <span className="text-emerald-500 font-semibold">Zero breaches</span>
            )}
          </div>
        </div>
      </div>

      {/* Embedded Threat Search & Interactive Filter Toolbar */}
      <div className={`p-3.5 border rounded-xl mb-4 space-y-2.5 shadow-xs ${
        isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-950 border-slate-800'
      }`}>
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2 text-xs">
          {/* Quick Filter Buttons */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] text-slate-500 uppercase font-semibold mr-1">
              Filter Threat:
            </span>
            {(
              [
                { id: 'ALL', label: 'All Events' },
                { id: 'CRITICAL', label: 'Critical (≥75%)' },
                { id: 'SUSPICIOUS', label: 'Elevated (30-74%)' },
                { id: 'NOMINAL', label: 'Nominal (<30%)' }
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                onClick={() => setFilterMode(tab.id)}
                className={`px-2.5 py-1 rounded-lg text-[11px] transition-all border ${
                  filterMode === tab.id
                    ? tab.id === 'CRITICAL'
                      ? 'bg-rose-500/20 border-rose-500 text-rose-600 dark:text-rose-300 font-bold'
                      : tab.id === 'SUSPICIOUS'
                      ? 'bg-amber-500/20 border-amber-500 text-amber-700 dark:text-amber-300 font-bold'
                      : tab.id === 'NOMINAL'
                      ? 'bg-emerald-500/20 border-emerald-500 text-emerald-700 dark:text-emerald-300 font-bold'
                      : 'bg-blue-500/20 border-blue-500 text-blue-700 dark:text-blue-300 font-bold'
                    : isLight
                    ? 'bg-white border-slate-200 text-slate-600 hover:text-slate-950 hover:border-slate-300 shadow-xs'
                    : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Search Input */}
          <div className="relative flex-1 max-w-xs">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search threat events..."
              value={threatSearch}
              onChange={(e) => setThreatSearch(e.target.value)}
              className={`w-full pl-8 pr-6 py-1.5 border rounded-lg text-xs focus:outline-none focus:border-blue-500 shadow-xs ${
                isLight ? 'bg-white border-slate-200 text-slate-900' : 'bg-slate-900 border-slate-800 text-white'
              }`}
            />
            {threatSearch && (
              <button
                onClick={() => setThreatSearch('')}
                className="absolute right-2 top-2 text-slate-400 hover:text-slate-700 dark:hover:text-white"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>
        </div>

        {/* Targeted Principal Selector Chips */}
        {affectedPrincipals.length > 0 && (
          <div className="flex items-center gap-1.5 flex-wrap pt-1 text-[10px]">
            <span className="text-slate-500">Targeted Principals:</span>
            <button
              onClick={() => setSelectedPrincipal('ALL')}
              className={`px-2 py-0.5 rounded-lg border transition-all ${
                selectedPrincipal === 'ALL'
                  ? 'bg-blue-600 text-white border-blue-500'
                  : isLight
                  ? 'bg-white text-slate-700 border-slate-200 hover:border-slate-300 shadow-xs'
                  : 'bg-slate-900 text-slate-400 border-slate-800'
              }`}
            >
              All Principals
            </button>
            {affectedPrincipals.map((pr) => (
              <button
                key={pr}
                onClick={() => setSelectedPrincipal(selectedPrincipal === pr ? 'ALL' : pr)}
                className={`px-2 py-0.5 rounded-lg border flex items-center gap-1 transition-all ${
                  selectedPrincipal === pr
                    ? 'bg-rose-600 text-white border-rose-500 font-bold'
                    : isLight
                    ? 'bg-rose-50 text-rose-700 border-rose-200 hover:border-rose-300'
                    : 'bg-slate-900 text-rose-300 border-rose-900/50 hover:border-rose-700'
                }`}
              >
                <Lock className="w-2.5 h-2.5 text-rose-500" />
                {pr}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Latest Critical Breach Context Banner or Filtered Event Preview */}
      {recentCritical ? (
        <div
          id="latest-critical-incident"
          className={`p-3.5 border rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs shadow-xs ${
            isLight ? 'bg-rose-50 border-rose-200' : 'bg-slate-950 border-rose-500/30'
          }`}
        >
          <div className="flex items-start gap-2.5">
            <div className="p-1.5 rounded-lg bg-rose-500/15 text-rose-500 border border-rose-500/30 shrink-0 mt-0.5 sm:mt-0">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`font-bold ${isLight ? 'text-slate-900' : 'text-white'}`}>Latest Intercept:</span>
                <span className="text-rose-500 font-bold">{recentCritical.username}</span>
                <span className="text-slate-400">•</span>
                <code className="text-blue-500 bg-blue-500/10 px-1.5 py-0.5 rounded text-[10px] font-semibold border border-blue-500/20">
                  {recentCritical.requested_function}
                </code>
                <span className="text-slate-400">•</span>
                <span className="text-rose-500 font-bold">Risk {recentCritical.calculated_risk}%</span>
              </div>
              <p className={`text-[11px] mt-0.5 ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                {recentCritical.reason}
              </p>
            </div>
          </div>

          <div className="text-[10px] text-slate-400 whitespace-nowrap self-end sm:self-center">
            {new Date(recentCritical.timestamp).toLocaleTimeString()}
          </div>
        </div>
      ) : (
        <div
          id="nominal-status-banner"
          className={`p-3 border rounded-xl flex items-center justify-between text-xs shadow-xs ${
            isLight ? 'bg-emerald-50 border-emerald-200 text-slate-700' : 'bg-slate-950 border-slate-800 text-slate-400'
          }`}
        >
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-500" />
            <span>
              Zero critical blocks (Risk &gt; 75%) recorded. Edge firewalls nominal with sequential Markov pattern verification.
            </span>
          </div>
          <span className="text-[10px] text-slate-400 font-mono">Standby Mode</span>
        </div>
      )}
    </section>
  );
};
