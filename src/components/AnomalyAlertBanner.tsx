import React, { useState } from 'react';
import {
  AlertOctagon,
  ShieldAlert,
  ChevronDown,
  ChevronUp,
  CheckCircle,
  X,
  ExternalLink,
  ShieldCheck,
  Flame,
  Radio,
  Sliders,
  UserX,
  ArrowRight
} from 'lucide-react';
import { AnomalyAlert } from '../types.ts';

interface AnomalyAlertBannerProps {
  alerts: AnomalyAlert[];
  onAcknowledgeAlert: (id: string) => void;
  onQuarantineUser?: (username: string) => void;
  onNavigateToAudit?: () => void;
  onNavigateToAdmin?: () => void;
}

export const AnomalyAlertBanner: React.FC<AnomalyAlertBannerProps> = ({
  alerts,
  onAcknowledgeAlert,
  onQuarantineUser,
  onNavigateToAudit,
  onNavigateToAdmin
}) => {
  const [isExpanded, setIsExpanded] = useState(true);

  const activeAlerts = alerts.filter(a => !a.acknowledged);

  if (activeAlerts.length === 0) return null;

  const topAlert = activeAlerts[0];
  const criticalCount = activeAlerts.filter(a => a.severity === 'CRITICAL').length;

  return (
    <aside
      id="security-anomaly-alert-banner"
      aria-label="Security Anomaly Alert"
      className="mb-6 rounded-xl border border-rose-500/50 bg-gradient-to-r from-rose-950/70 via-slate-900 to-rose-950/40 p-4 font-mono shadow-2xl backdrop-blur-md relative overflow-hidden transition-all duration-300"
    >
      {/* Decorative pulse line */}
      <div className="absolute top-0 left-0 right-0 h-[2.5px] bg-rose-500 animate-pulse" />

      {/* Top Banner Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-rose-500/20 border border-rose-500/50 text-rose-400 shrink-0 animate-bounce">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-bold uppercase tracking-wider text-rose-300 flex items-center gap-1.5">
                <span className="inline-block w-2 h-2 rounded-full bg-rose-400 animate-ping" />
                Security Anomaly Detected
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-rose-500 text-white shadow-sm">
                {activeAlerts.length} Active Threat{activeAlerts.length > 1 ? 's' : ''}
              </span>
              {criticalCount > 0 && (
                <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                  {criticalCount} Critical Exploit
                </span>
              )}
            </div>
            <p className="text-xs text-slate-300 mt-0.5">
              <strong>[{topAlert.username}]</strong> {topAlert.message}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-auto shrink-0">
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="px-2.5 py-1 text-xs rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 flex items-center gap-1 transition-colors"
          >
            {isExpanded ? (
              <>
                <ChevronUp className="w-3.5 h-3.5" />
                Hide Details
              </>
            ) : (
              <>
                <ChevronDown className="w-3.5 h-3.5" />
                Review ({activeAlerts.length})
              </>
            )}
          </button>
        </div>
      </div>

      {/* Expanded Details Section */}
      {isExpanded && (
        <div className="mt-4 pt-3 border-t border-rose-500/20 space-y-3">
          <div className="text-[11px] text-slate-400">
            Real-time heuristic evaluation intercepted anomalous behavior at edge firewall:
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {activeAlerts.map((alert) => (
              <div
                key={alert.id}
                className="p-3 bg-slate-950/80 border border-rose-900/60 rounded-lg flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded uppercase font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30">
                      {alert.type.replace(/_/g, ' ')}
                    </span>
                    <span className="text-[10px] text-slate-400">
                      {alert.timestamp}
                    </span>
                  </div>

                  <div className="text-xs font-bold text-white mt-2">
                    Principal: <span className="text-rose-400">{alert.username}</span>
                  </div>

                  <div className="text-[11px] text-slate-300 mt-1">
                    Route: <code className="text-blue-400 bg-slate-900 px-1.5 py-0.5 rounded">{alert.endpoint}</code>
                  </div>

                  <div className="text-[11px] text-slate-400 mt-1.5 line-clamp-2">
                    {alert.message}
                  </div>

                  <div className="mt-2 text-[10px] text-emerald-400 bg-emerald-950/30 px-2 py-1 rounded border border-emerald-500/20 flex items-center gap-1.5">
                    <ShieldCheck className="w-3 h-3 text-emerald-400 shrink-0" />
                    <span>Mitigation: {alert.mitigation}</span>
                  </div>
                </div>

                <div className="mt-3 pt-2 border-t border-slate-900 flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5">
                    {onQuarantineUser && (
                      <button
                        type="button"
                        onClick={() => onQuarantineUser(alert.username)}
                        className="px-2 py-1 text-[10px] rounded bg-rose-900/50 hover:bg-rose-800 text-rose-200 border border-rose-700/60 flex items-center gap-1 transition-colors"
                        title="Quarantine this principal by setting base risk to 100%"
                      >
                        <UserX className="w-3 h-3" />
                        Quarantine
                      </button>
                    )}
                    {onNavigateToAdmin && (
                      <button
                        type="button"
                        onClick={onNavigateToAdmin}
                        className="px-2 py-1 text-[10px] rounded bg-blue-900/50 hover:bg-blue-800 text-blue-200 border border-blue-700/60 flex items-center gap-1 transition-colors"
                      >
                        Admin Cockpit
                      </button>
                    )}
                  </div>

                  <button
                    type="button"
                    onClick={() => onAcknowledgeAlert(alert.id)}
                    className="px-2 py-1 text-[10px] rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white flex items-center gap-1 transition-colors"
                  >
                    <CheckCircle className="w-3 h-3 text-emerald-400" />
                    Acknowledge
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </aside>
  );
};
