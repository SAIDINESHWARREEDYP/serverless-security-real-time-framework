import React, { useState, useMemo, useEffect, useRef } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Clock,
  Activity,
  AlertTriangle,
  Zap,
  Filter,
  Play,
  Pause,
  RotateCcw,
  Info,
  Lock,
  ChevronRight,
  UserX,
  Target,
  FileWarning,
  Eye,
  Crosshair,
  TrendingUp,
  Cpu
} from 'lucide-react';
import { SecurityAuditLog } from '../types.ts';
import { useTheme } from '../context/ThemeContext.tsx';

interface InteractiveSecurityTimelineProps {
  logs: SecurityAuditLog[];
  onSelectLog?: (log: SecurityAuditLog) => void;
  selectedLogId?: number | null;
}

export type TimelineFilter = 'ALL' | 'ATTACK_PATTERNS' | 'BLOCKED_ONLY' | 'SEQUENCE_VIOLATIONS' | 'REVOCATION_EVENTS' | 'CRITICAL_RISK';

interface DetectedAttackPattern {
  id: string;
  type: 'RAPID_BRUTE_FORCE' | 'SEQUENCE_TAMPERING' | 'PRIVILEGE_ESCALATION' | 'REVOKED_REPLAY' | 'FAIL_CLOSED_FAULT';
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  eventIds: number[];
  principal: string;
  timeSpan: string;
}

export const InteractiveSecurityTimeline: React.FC<InteractiveSecurityTimelineProps> = ({
  logs,
  onSelectLog,
  selectedLogId: controlledSelectedLogId
}) => {
  const { isLight } = useTheme();
  const [internalSelectedId, setInternalSelectedId] = useState<number | null>(null);
  const [timelineFilter, setTimelineFilter] = useState<TimelineFilter>('ALL');
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackIndex, setPlaybackIndex] = useState<number>(0);
  const playbackTimerRef = useRef<NodeJS.Timeout | null>(null);

  const selectedLogId = controlledSelectedLogId !== undefined ? controlledSelectedLogId : internalSelectedId;

  // Chronologically sorted logs (oldest first for progression flow)
  const chronologicalLogs = useMemo(() => {
    return [...logs].sort((a, b) => {
      const timeA = new Date(a.timestamp).getTime();
      const timeB = new Date(b.timestamp).getTime();
      if (!isNaN(timeA) && !isNaN(timeB) && timeA !== timeB) {
        return timeA - timeB;
      }
      return a.id - b.id;
    });
  }, [logs]);

  // Attack Pattern Heuristics Engine
  const detectedPatterns = useMemo(() => {
    const patterns: DetectedAttackPattern[] = [];
    if (chronologicalLogs.length === 0) return patterns;

    // 1. Detect Markov Sequence Violations
    const sequenceViolationLogs = chronologicalLogs.filter(
      (l) => l.event_type === 'SEQUENCE_VIOLATION' || l.reason.toLowerCase().includes('sequence footprint')
    );
    if (sequenceViolationLogs.length > 0) {
      patterns.push({
        id: 'pat-seq-tamper',
        type: 'SEQUENCE_TAMPERING',
        title: 'Markov Invariant Workflow Deviation',
        description: `Adversarial hopping identified across ${sequenceViolationLogs.length} call transition(s), bypassing declared state graph.`,
        severity: 'HIGH',
        eventIds: sequenceViolationLogs.map((l) => l.id),
        principal: sequenceViolationLogs[0].username,
        timeSpan: `${sequenceViolationLogs.length} event(s)`
      });
    }

    // 2. Detect Revoked Session Replay / Bypass
    const revocationLogs = chronologicalLogs.filter(
      (l) => l.event_type === 'SESSION_REVOKED' || l.reason.toLowerCase().includes('session revoked')
    );
    if (revocationLogs.length > 0) {
      patterns.push({
        id: 'pat-revoked-replay',
        type: 'REVOKED_REPLAY',
        title: 'Revoked Token Signature Replay',
        description: `Compromised credential reuse attempted after real-time administrator termination in D1.`,
        severity: 'CRITICAL',
        eventIds: revocationLogs.map((l) => l.id),
        principal: revocationLogs[0].username,
        timeSpan: `${revocationLogs.length} attempt(s)`
      });
    }

    // 3. Detect Rapid Probing / Brute Force Burst (> 3 requests within 10 seconds for same user)
    const userEventGroups = new Map<string, SecurityAuditLog[]>();
    chronologicalLogs.forEach((l) => {
      const list = userEventGroups.get(l.username) || [];
      list.push(l);
      userEventGroups.set(l.username, list);
    });

    userEventGroups.forEach((userLogs, username) => {
      if (userLogs.length >= 3) {
        for (let i = 0; i < userLogs.length - 2; i++) {
          const t1 = new Date(userLogs[i].timestamp).getTime();
          const t3 = new Date(userLogs[i + 2].timestamp).getTime();
          if (!isNaN(t1) && !isNaN(t3) && (t3 - t1) <= 15000) {
            patterns.push({
              id: `pat-burst-${username}-${i}`,
              type: 'RAPID_BRUTE_FORCE',
              title: `High-Frequency Invocation Burst [${username}]`,
              description: `Rapid consecutive API probe velocity (3+ requests within 15s) violating edge sliding window.`,
              severity: 'HIGH',
              eventIds: [userLogs[i].id, userLogs[i + 1].id, userLogs[i + 2].id],
              principal: username,
              timeSpan: `${Math.max(1, Math.round((t3 - t1) / 1000))}s window`
            });
            break;
          }
        }
      }
    });

    // 4. Detect Fail-Closed Faults
    const failClosedLogs = chronologicalLogs.filter(
      (l) => l.event_type === 'SECURITY_EXCEPTION_FAIL_CLOSED' || l.reason.toLowerCase().includes('fail-closed')
    );
    if (failClosedLogs.length > 0) {
      patterns.push({
        id: 'pat-fail-closed',
        type: 'FAIL_CLOSED_FAULT',
        title: 'Pipeline Security Exception [Fail-Closed]',
        description: `System error/timeout intercepted; automatically elevated to 100% Critical Risk to preserve perimeter integrity.`,
        severity: 'CRITICAL',
        eventIds: failClosedLogs.map((l) => l.id),
        principal: failClosedLogs[0].username,
        timeSpan: `${failClosedLogs.length} exception(s)`
      });
    }

    return patterns;
  }, [chronologicalLogs]);

  // Set of event IDs belonging to any detected attack pattern
  const patternEventIdSet = useMemo(() => {
    const set = new Set<number>();
    detectedPatterns.forEach((p) => p.eventIds.forEach((id) => set.add(id)));
    return set;
  }, [detectedPatterns]);

  // Filtered timeline logs
  const filteredTimelineLogs = useMemo(() => {
    return chronologicalLogs.filter((log) => {
      if (timelineFilter === 'ALL') return true;
      if (timelineFilter === 'ATTACK_PATTERNS') return patternEventIdSet.has(log.id) || log.status === 'BLOCKED';
      if (timelineFilter === 'BLOCKED_ONLY') return log.status === 'BLOCKED';
      if (timelineFilter === 'SEQUENCE_VIOLATIONS') {
        return log.event_type === 'SEQUENCE_VIOLATION' || log.reason.toLowerCase().includes('sequence');
      }
      if (timelineFilter === 'REVOCATION_EVENTS') {
        return log.event_type === 'SESSION_REVOKED' || log.event_type === 'SESSION_REVOCATION_EXECUTED';
      }
      if (timelineFilter === 'CRITICAL_RISK') return log.calculated_risk >= 75;
      return true;
    });
  }, [chronologicalLogs, timelineFilter, patternEventIdSet]);

  // Automatically select latest event on mount if none selected
  useEffect(() => {
    if (selectedLogId === null && filteredTimelineLogs.length > 0) {
      const initial = filteredTimelineLogs[filteredTimelineLogs.length - 1];
      setInternalSelectedId(initial.id);
      if (onSelectLog) onSelectLog(initial);
    }
  }, [filteredTimelineLogs, selectedLogId, onSelectLog]);

  // Playback engine for chronological step-through
  useEffect(() => {
    if (isPlaying && filteredTimelineLogs.length > 0) {
      playbackTimerRef.current = setInterval(() => {
        setPlaybackIndex((prev) => {
          const next = (prev + 1) % filteredTimelineLogs.length;
          const log = filteredTimelineLogs[next];
          if (log) {
            setInternalSelectedId(log.id);
            if (onSelectLog) onSelectLog(log);
          }
          return next;
        });
      }, 1600);
    } else if (playbackTimerRef.current) {
      clearInterval(playbackTimerRef.current);
      playbackTimerRef.current = null;
    }

    return () => {
      if (playbackTimerRef.current) clearInterval(playbackTimerRef.current);
    };
  }, [isPlaying, filteredTimelineLogs, onSelectLog]);

  const handleSelectEvent = (log: SecurityAuditLog, index: number) => {
    setInternalSelectedId(log.id);
    setPlaybackIndex(index);
    if (onSelectLog) onSelectLog(log);
  };

  const selectedLog = useMemo(() => {
    return logs.find((l) => l.id === selectedLogId) || filteredTimelineLogs[filteredTimelineLogs.length - 1] || null;
  }, [logs, selectedLogId, filteredTimelineLogs]);

  // Helper for formatting time
  const formatTime = (ts: string) => {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  return (
    <div className={`rounded-2xl border transition-all ${
      isLight ? 'bg-white border-slate-200 text-slate-900' : 'bg-[#0f172a] border-[#1e293b] text-slate-100'
    } p-4 sm:p-5 shadow-xs`}>
      {/* 1. Header Toolbar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b pb-3 mb-4 border-slate-200 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">
              Chronological Security Event Timeline &amp; Attack Pattern Detector
            </h3>
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
            Real-time forensic sequence reconstruction • Detects Markov deviations, rapid probe bursts &amp; revoked token replays
          </p>
        </div>

        {/* Playback & Step Controls */}
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setIsPlaying(!isPlaying)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-all cursor-pointer ${
              isPlaying
                ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                : 'bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
            }`}
            title={isPlaying ? 'Pause chronological playback' : 'Play chronological simulation step-by-step'}
          >
            {isPlaying ? (
              <>
                <Pause className="w-3.5 h-3.5" />
                <span>Pause</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Play Timeline</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={() => {
              setIsPlaying(false);
              setPlaybackIndex(0);
              if (filteredTimelineLogs[0]) {
                handleSelectEvent(filteredTimelineLogs[0], 0);
              }
            }}
            className="p-1.5 rounded-lg border border-slate-300 dark:border-slate-700 text-slate-500 hover:text-slate-900 dark:hover:text-white transition-colors"
            title="Rewind to earliest event"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>

          <div className="text-[11px] font-mono tabular-nums text-slate-400 px-2 py-1 rounded bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
            {filteredTimelineLogs.length > 0 ? `${playbackIndex + 1}/${filteredTimelineLogs.length}` : '0/0'}
          </div>
        </div>
      </div>

      {/* 2. Detected Attack Patterns Alert Strip */}
      {detectedPatterns.length > 0 && (
        <div className="mb-4 space-y-2">
          {detectedPatterns.map((pat) => (
            <div
              key={pat.id}
              className={`p-3 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 transition-all ${
                pat.severity === 'CRITICAL'
                  ? 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                  : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
              }`}
            >
              <div className="flex items-start gap-2.5">
                <AlertTriangle className={`w-4 h-4 shrink-0 mt-0.5 ${
                  pat.severity === 'CRITICAL' ? 'text-rose-400' : 'text-amber-400'
                }`} />
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-bold text-xs text-white">
                      {pat.title}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-black/40 border border-white/10 uppercase">
                      Target: {pat.principal}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-black/40 border border-white/10">
                      {pat.timeSpan}
                    </span>
                  </div>
                  <p className="text-[11px] opacity-90 mt-0.5">
                    {pat.description}
                  </p>
                </div>
              </div>

              <button
                type="button"
                onClick={() => {
                  const targetLog = logs.find((l) => l.id === pat.eventIds[0]);
                  if (targetLog) {
                    setInternalSelectedId(targetLog.id);
                    if (onSelectLog) onSelectLog(targetLog);
                  }
                }}
                className="shrink-0 text-[11px] font-semibold px-2.5 py-1 rounded bg-white/10 hover:bg-white/20 text-white transition-colors flex items-center gap-1 self-start sm:self-center"
              >
                <span>Inspect Trace</span>
                <ChevronRight className="w-3 h-3" />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* 3. Interactive Filter Tabs (Buttons with click handlers) */}
      <div className="flex items-center gap-1.5 mb-4 overflow-x-auto pb-1 text-xs no-scrollbar">
        <span className="text-[10px] text-slate-400 uppercase font-semibold mr-1 flex items-center gap-1">
          <Filter className="w-3 h-3" />
          Filter:
        </span>
        <button
          type="button"
          onClick={() => setTimelineFilter('ALL')}
          className={`px-2.5 py-1 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 ${
            timelineFilter === 'ALL'
              ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
              : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
          }`}
        >
          All Events ({chronologicalLogs.length})
        </button>
        <button
          type="button"
          onClick={() => setTimelineFilter('ATTACK_PATTERNS')}
          className={`px-2.5 py-1 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 flex items-center gap-1 ${
            timelineFilter === 'ATTACK_PATTERNS'
              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
              : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
          }`}
        >
          <Target className="w-3 h-3 text-rose-400" />
          Attack Patterns ({patternEventIdSet.size})
        </button>
        <button
          type="button"
          onClick={() => setTimelineFilter('BLOCKED_ONLY')}
          className={`px-2.5 py-1 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 ${
            timelineFilter === 'BLOCKED_ONLY'
              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
              : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
          }`}
        >
          Blocked Interceptions ({chronologicalLogs.filter((l) => l.status === 'BLOCKED').length})
        </button>
        <button
          type="button"
          onClick={() => setTimelineFilter('SEQUENCE_VIOLATIONS')}
          className={`px-2.5 py-1 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 ${
            timelineFilter === 'SEQUENCE_VIOLATIONS'
              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
              : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
          }`}
        >
          Sequence Violations
        </button>
        <button
          type="button"
          onClick={() => setTimelineFilter('REVOCATION_EVENTS')}
          className={`px-2.5 py-1 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 ${
            timelineFilter === 'REVOCATION_EVENTS'
              ? 'bg-purple-500/20 text-purple-400 border border-purple-500/40'
              : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
          }`}
        >
          Revocations &amp; Replays
        </button>
        <button
          type="button"
          onClick={() => setTimelineFilter('CRITICAL_RISK')}
          className={`px-2.5 py-1 rounded-lg font-medium transition-colors whitespace-nowrap shrink-0 ${
            timelineFilter === 'CRITICAL_RISK'
              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
              : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
          }`}
        >
          Critical Risk (≥75%)
        </button>
      </div>

      {/* 4. Horizontal Chronological Ribbon */}
      <div className="relative mb-5 p-3 rounded-xl bg-slate-900/60 dark:bg-black/40 border border-slate-200 dark:border-slate-800 overflow-x-auto">
        <div className="flex items-center gap-3 min-w-max py-2">
          {filteredTimelineLogs.map((log, index) => {
            const isSelected = log.id === selectedLogId;
            const isBlocked = log.status === 'BLOCKED';
            const isPartOfPattern = patternEventIdSet.has(log.id);
            const isCritical = log.calculated_risk >= 75;

            return (
              <div key={log.id} className="flex items-center">
                <button
                  type="button"
                  onClick={() => handleSelectEvent(log, index)}
                  className={`group relative flex flex-col items-center cursor-pointer transition-all ${
                    isSelected ? 'scale-110 z-10' : 'hover:scale-105 opacity-80 hover:opacity-100'
                  }`}
                  title={`[#${log.id}] ${log.username} -> ${log.requested_function} (${log.calculated_risk}%)`}
                >
                  {/* Timestamp label */}
                  <span className={`text-[9px] font-mono tabular-nums mb-1 ${
                    isSelected ? 'text-cyan-400 font-bold' : 'text-slate-500'
                  }`}>
                    {formatTime(log.timestamp)}
                  </span>

                  {/* Node Circle */}
                  <div
                    className={`w-7 h-7 rounded-full flex items-center justify-center border-2 transition-all shadow-xs ${
                      isBlocked
                        ? 'bg-rose-950 text-rose-300 border-rose-500'
                        : isCritical
                        ? 'bg-amber-950 text-amber-300 border-amber-500'
                        : log.calculated_risk >= 25
                        ? 'bg-cyan-950 text-cyan-300 border-cyan-500'
                        : 'bg-emerald-950 text-emerald-300 border-emerald-500'
                    } ${
                      isSelected
                        ? 'ring-2 ring-cyan-400 ring-offset-2 ring-offset-slate-900 shadow-cyan-500/50'
                        : ''
                    } ${isPartOfPattern ? 'animate-pulse' : ''}`}
                  >
                    {isBlocked ? (
                      <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                    ) : (
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                    )}
                  </div>

                  {/* Risk Badge */}
                  <span className={`text-[8px] font-mono tabular-nums mt-1 px-1 rounded ${
                    isBlocked
                      ? 'bg-rose-500/20 text-rose-400'
                      : isCritical
                      ? 'bg-amber-500/20 text-amber-400'
                      : 'text-slate-400'
                  }`}>
                    {log.calculated_risk}%
                  </span>

                  {/* Micro label for function */}
                  <span className="text-[8px] text-slate-500 max-w-[60px] truncate mt-0.5">
                    {log.requested_function.replace('/api/', '')}
                  </span>
                </button>

                {/* Connecting track line between nodes */}
                {index < filteredTimelineLogs.length - 1 && (
                  <div className={`w-6 h-0.5 mx-1 transition-colors ${
                    isBlocked || filteredTimelineLogs[index + 1]?.status === 'BLOCKED'
                      ? 'bg-rose-500/40'
                      : 'bg-slate-700/60'
                  }`} />
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* 5. Forensic Detail Inspector for Selected Event */}
      {selectedLog ? (
        <div className={`p-4 rounded-xl border transition-all ${
          selectedLog.status === 'BLOCKED'
            ? 'bg-rose-950/20 border-rose-500/30'
            : 'bg-slate-900/50 border-slate-700/50'
        }`}>
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b pb-2 mb-3 border-slate-800">
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                selectedLog.status === 'BLOCKED'
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                  : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
              }`}>
                {selectedLog.status}
              </span>
              <span className="font-mono text-xs text-white font-bold">
                Event #{selectedLog.id}
              </span>
              <span className="text-slate-400 text-xs">·</span>
              <span className="font-mono text-xs text-slate-300">
                {selectedLog.username}
              </span>
              <span className="text-slate-400 text-xs">·</span>
              <span className="font-mono text-xs text-cyan-400">
                {selectedLog.requested_function}
              </span>
            </div>

            <div className="flex items-center gap-3 text-xs font-mono tabular-nums text-slate-400">
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3 text-slate-500" />
                {new Date(selectedLog.timestamp).toISOString()}
              </span>
              {typeof selectedLog.verification_latency_ms === 'number' && (
                <span className="flex items-center gap-1 text-cyan-300">
                  <Cpu className="w-3 h-3 text-cyan-400" />
                  {selectedLog.verification_latency_ms.toFixed(3)} ms
                </span>
              )}
            </div>
          </div>

          {/* Forensic Key Metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs mb-3">
            <div className="p-2.5 rounded-lg bg-black/30 border border-white/5">
              <span className="text-[10px] text-slate-400 block uppercase font-mono">Calculated Risk</span>
              <span className={`text-base font-bold font-mono ${
                selectedLog.calculated_risk >= 75
                  ? 'text-rose-400'
                  : selectedLog.calculated_risk >= 50
                  ? 'text-amber-400'
                  : selectedLog.calculated_risk >= 25
                  ? 'text-cyan-400'
                  : 'text-emerald-400'
              }`}>
                {selectedLog.calculated_risk}%
              </span>
            </div>

            <div className="p-2.5 rounded-lg bg-black/30 border border-white/5">
              <span className="text-[10px] text-slate-400 block uppercase font-mono">Event Classifier</span>
              <span className="text-xs font-semibold font-mono text-white truncate block">
                {selectedLog.event_type || 'STANDARD_VERIFICATION'}
              </span>
            </div>

            <div className="p-2.5 rounded-lg bg-black/30 border border-white/5">
              <span className="text-[10px] text-slate-400 block uppercase font-mono">Attack Association</span>
              <span className={`text-xs font-semibold font-mono truncate block ${
                patternEventIdSet.has(selectedLog.id) ? 'text-rose-400' : 'text-slate-400'
              }`}>
                {patternEventIdSet.has(selectedLog.id) ? 'ATTACK PATTERN' : 'NOMINAL TRACE'}
              </span>
            </div>

            <div className="p-2.5 rounded-lg bg-black/30 border border-white/5">
              <span className="text-[10px] text-slate-400 block uppercase font-mono">Edge Verdict</span>
              <span className={`text-xs font-semibold font-mono ${
                selectedLog.status === 'BLOCKED' ? 'text-rose-400' : 'text-emerald-400'
              }`}>
                {selectedLog.status === 'BLOCKED' ? 'FIREWALL DROP' : 'PERSISTED D1'}
              </span>
            </div>
          </div>

          {/* Reason / Mitigation Analysis */}
          <div className="p-3 rounded-lg bg-black/40 border border-white/5">
            <span className="text-[10px] text-slate-400 block uppercase font-mono mb-1">
              Mitigation Heuristics &amp; Ledger Reasoning:
            </span>
            <p className="text-xs text-slate-200 font-mono leading-relaxed">
              {selectedLog.reason}
            </p>
          </div>
        </div>
      ) : (
        <div className="p-6 text-center text-xs text-slate-400">
          Select an event node from the timeline ribbon to inspect forensic parameters.
        </div>
      )}
    </div>
  );
};
