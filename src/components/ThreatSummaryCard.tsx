import React, { useMemo } from 'react';
import { AlertTriangle, ShieldAlert, Activity, ShieldCheck, Flame, Radio, ArrowUpRight, Lock } from 'lucide-react';
import { SecurityAuditLog } from '../types.ts';

interface ThreatSummaryCardProps {
  logs: SecurityAuditLog[];
}

export const ThreatSummaryCard: React.FC<ThreatSummaryCardProps> = ({ logs }) => {
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
    const critical = logs.filter((l) => l.calculated_risk > 75 && l.status === 'BLOCKED');
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
      color: 'text-[#00ff87]',
      bg: 'bg-[#00ff87]/10',
      border: 'border-[#00ff87]/30',
      icon: ShieldCheck
    };

    if (critical.length >= 3 || avgOverall >= 60) {
      condition = {
        label: 'CRITICAL THREAT DEFCON 1',
        color: 'text-[#ff4a6b]',
        bg: 'bg-[#ff4a6b]/15',
        border: 'border-[#ff4a6b]/40',
        icon: ShieldAlert
      };
    } else if (critical.length > 0 || avgOverall >= 30) {
      condition = {
        label: 'ELEVATED MITIGATION',
        color: 'text-amber-400',
        bg: 'bg-amber-400/15',
        border: 'border-amber-400/40',
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

  const StatusIcon = threatCondition.icon;

  return (
    <section
      id="threat-summary-card"
      aria-label="Real-time Threat Summary"
      className="bg-[#131c2e] border border-[#223452] p-4 sm:p-5 rounded-md font-mono relative overflow-hidden"
    >
      {/* Decorative top accent line reflecting threat level */}
      <div
        className={`absolute top-0 left-0 right-0 h-[3px] transition-colors duration-500 ${
          criticalCount > 0 ? 'bg-[#ff4a6b]' : avgThreatLevel > 20 ? 'bg-amber-400' : 'bg-[#00d2ff]'
        }`}
      />

      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 mb-4 border-b border-[#223452]">
        <div className="flex items-center gap-2.5">
          <div className={`p-2 rounded border ${threatCondition.bg} ${threatCondition.border} ${threatCondition.color}`}>
            <StatusIcon className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">
                Real-Time Threat Summary
              </h2>
              <span className="flex items-center gap-1 text-[10px] text-[#6b7c96]">
                <Radio className="w-3 h-3 text-[#00d2ff] animate-pulse" />
                Live Heuristics
              </span>
            </div>
            <p className="text-[11px] text-[#6b7c96] mt-0.5">
              Automated aggregation of high-risk security incidents (Risk &gt; 75%) and sequential threat scoring
            </p>
          </div>
        </div>

        {/* Global Threat Condition Badge */}
        <div
          id="threat-condition-badge"
          className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider border self-start sm:self-auto ${threatCondition.bg} ${threatCondition.border} ${threatCondition.color}`}
        >
          <span className="w-2 h-2 rounded-full bg-current animate-ping" />
          <span>{threatCondition.label}</span>
        </div>
      </div>

      {/* Core Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
        {/* Metric 1: Critical Blocks (Risk > 75) */}
        <div
          id="metric-critical-blocks"
          className="bg-[#090d16] border border-[#223452] p-3.5 rounded flex flex-col justify-between"
        >
          <div className="flex items-center justify-between text-[11px] text-[#6b7c96] uppercase font-bold">
            <span>Critical Blocks (Risk &gt; 75)</span>
            <ShieldAlert className="w-4 h-4 text-[#ff4a6b]" />
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className={`text-2xl font-extrabold ${criticalCount > 0 ? 'text-[#ff4a6b]' : 'text-white'}`}>
              {criticalCount}
            </span>
            <span className="text-[11px] text-[#6b7c96]">
              of {totalBlocks} total blocked
            </span>
          </div>
          <div className="text-[10px] text-[#94a3b8] mt-1 flex items-center justify-between">
            <span>Cutoff Threshold: 75%</span>
            <span className={criticalCount > 0 ? 'text-[#ff4a6b]' : 'text-[#00ff87]'}>
              {criticalCount > 0 ? 'MITIGATED' : 'ALL CLEAR'}
            </span>
          </div>
        </div>

        {/* Metric 2: Average Threat Level */}
        <div
          id="metric-avg-threat"
          className="bg-[#090d16] border border-[#223452] p-3.5 rounded flex flex-col justify-between"
        >
          <div className="flex items-center justify-between text-[11px] text-[#6b7c96] uppercase font-bold">
            <span>Average Threat Level</span>
            <Flame className={`w-4 h-4 ${avgThreatLevel >= 75 ? 'text-[#ff4a6b]' : avgThreatLevel >= 30 ? 'text-amber-400' : 'text-[#00ff87]'}`} />
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span
              className={`text-2xl font-extrabold ${
                avgThreatLevel >= 75
                  ? 'text-[#ff4a6b]'
                  : avgThreatLevel >= 30
                  ? 'text-amber-400'
                  : 'text-[#00ff87]'
              }`}
            >
              {avgThreatLevel}%
            </span>
            <span className="text-[11px] text-[#6b7c96]">
              {logs.length} evaluated
            </span>
          </div>
          <div className="w-full bg-[#131c2e] h-1.5 rounded-full overflow-hidden mt-1.5 border border-[#223452]">
            <div
              className={`h-full transition-all duration-300 ${
                avgThreatLevel >= 75
                  ? 'bg-[#ff4a6b]'
                  : avgThreatLevel >= 30
                  ? 'bg-amber-400'
                  : 'bg-[#00ff87]'
              }`}
              style={{ width: `${Math.min(avgThreatLevel, 100)}%` }}
            />
          </div>
        </div>

        {/* Metric 3: Critical Mean Severity */}
        <div
          id="metric-crit-severity"
          className="bg-[#090d16] border border-[#223452] p-3.5 rounded flex flex-col justify-between"
        >
          <div className="flex items-center justify-between text-[11px] text-[#6b7c96] uppercase font-bold">
            <span>Mean Critical Severity</span>
            <Activity className="w-4 h-4 text-[#00d2ff]" />
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-extrabold text-white">
              {avgCriticalRisk > 0 ? `${avgCriticalRisk}%` : '0%'}
            </span>
            <span className="text-[11px] text-[#6b7c96]">
              when intercepted
            </span>
          </div>
          <div className="text-[10px] text-[#94a3b8] mt-1 flex items-center justify-between">
            <span>Structural Penalty: +40%</span>
            <span>RBAC Penalty: 90%</span>
          </div>
        </div>

        {/* Metric 4: Intercepted Principals */}
        <div
          id="metric-affected-principals"
          className="bg-[#090d16] border border-[#223452] p-3.5 rounded flex flex-col justify-between"
        >
          <div className="flex items-center justify-between text-[11px] text-[#6b7c96] uppercase font-bold">
            <span>Targeted Principals</span>
            <Lock className="w-4 h-4 text-purple-400" />
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-extrabold text-white">
              {affectedPrincipals.length}
            </span>
            <span className="text-[11px] text-[#6b7c96]">
              flagged identity profiles
            </span>
          </div>
          <div className="text-[10px] text-[#94a3b8] mt-1 truncate">
            {affectedPrincipals.length > 0 ? (
              <span className="text-[#ff4a6b] font-bold">
                {affectedPrincipals.join(', ')}
              </span>
            ) : (
              <span className="text-[#00ff87]">No identity breaches</span>
            )}
          </div>
        </div>
      </div>

      {/* Latest Critical Breach Context Banner */}
      {recentCritical ? (
        <div
          id="latest-critical-incident"
          className="p-3 bg-[#090d16] border border-[#ff4a6b]/30 rounded flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
        >
          <div className="flex items-start gap-2.5">
            <div className="p-1.5 rounded bg-[#ff4a6b]/15 text-[#ff4a6b] border border-[#ff4a6b]/30 shrink-0 mt-0.5 sm:mt-0">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-white font-bold">Latest Intercept:</span>
                <span className="text-[#ff4a6b] font-bold">{recentCritical.username}</span>
                <span className="text-[#6b7c96]">•</span>
                <code className="text-[#00d2ff] bg-[#00d2ff]/10 px-1 rounded text-[10px]">
                  {recentCritical.requested_function}
                </code>
                <span className="text-[#6b7c96]">•</span>
                <span className="text-[#ff4a6b] font-bold">Risk {recentCritical.calculated_risk}%</span>
              </div>
              <p className="text-[11px] text-[#94a3b8] mt-0.5">
                {recentCritical.reason}
              </p>
            </div>
          </div>

          <div className="text-[10px] text-[#6b7c96] whitespace-nowrap self-end sm:self-center">
            {new Date(recentCritical.timestamp).toLocaleTimeString()}
          </div>
        </div>
      ) : (
        <div
          id="nominal-status-banner"
          className="p-2.5 bg-[#090d16] border border-[#223452] rounded flex items-center justify-between text-xs text-[#6b7c96]"
        >
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-[#00ff87]" />
            <span>
              Zero critical blocks (Risk &gt; 75%) recorded. Firewall active with sequential pattern verification.
            </span>
          </div>
          <span className="text-[10px] text-[#00d2ff]">Standby Mode</span>
        </div>
      )}
    </section>
  );
};
