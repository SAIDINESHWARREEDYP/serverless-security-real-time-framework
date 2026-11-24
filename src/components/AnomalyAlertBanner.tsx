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
import { useTheme } from '../context/ThemeContext.tsx';

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
  const { isLight } = useTheme();
  const [isExpanded, setIsExpanded] = useState(true);

  const activeAlerts = alerts.filter(a => !a.acknowledged);

  if (activeAlerts.length === 0) return null;

  const topAlert = activeAlerts[0];
  const criticalCount = activeAlerts.filter(a => a.severity === 'CRITICAL').length;

  return (
    <aside
      id="security-anomaly-alert-banner"
      aria-label="Security Anomaly Alert"
      className={`mb-6 rounded-xl border p-4 font-mono shadow-lg backdrop-blur-md relative overflow-hidden transition-all duration-300 ${
        isLight
          ? 'border-rose-300 bg-gradient-to-r from-rose-50 via-white to-rose-50/70 text-slate-900'
          : 'border-rose-500/50 bg-gradient-to-r from-rose-950/70 via-slate-900 to-rose-950/40 text-slate-100'
      }`}
    >
      {/* Top threat indicator line */}
      <div className="absolute top-0 left-0 right-0 h-[2.5px] bg-rose-500" />

      {/* Top Banner Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg border shrink-0 ${
            isLight
              ? 'bg-rose-100 border-rose-300 text-rose-700'
              : 'bg-rose-500/20 border-rose-500/50 text-rose-400'
          }`}>
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 ${
                isLight ? 'text-rose-800' : 'text-rose-300'
              }`}>
                <span className="inline-block w-2 h-2 rounded-full bg-rose-500" />
                Security Anomaly Detected
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-rose-600 text-white shadow-xs tabular-nums">
                {activeAlerts.length} Active Threat{activeAlerts.length > 1 ? 's' : ''}
              </span>
              {criticalCount > 0 && (
                <span className={`text-[10px] px-2 py-0.5 rounded font-bold border tabular-nums ${
                  isLight
                    ? 'bg-amber-100 text-amber-900 border-amber-300'
                    : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                }`}>
                  {criticalCount} Critical Exploit
                </span>
              )}
            </div>
            <p className={`text-xs mt-0.5 ${isLight ? 'text-slate-700' : 'text-slate-300'}`}>
              <strong>[{topAlert.username}]</strong> {topAlert.message}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-auto shrink-0">
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className={`px-2.5 py-1 text-xs rounded border flex items-center gap-1 transition-colors ${
              isLight
                ? 'bg-white hover:bg-slate-100 text-slate-800 border-slate-300'
                : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border-slate-700'
            }`}
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
        <div className={`mt-4 pt-3 border-t space-y-3 ${isLight ? 'border-rose-200' : 'border-rose-500/20'}`}>
          <div className={`text-[11px] ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
            Real-time heuristic evaluation intercepted anomalous behavior at edge firewall:
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {activeAlerts.map((alert) => (
              <div
                key={alert.id}
                className={`p-3 border rounded-lg flex flex-col justify-between ${
                  isLight
                    ? 'bg-white border-rose-200 shadow-xs'
                    : 'bg-slate-950/80 border-rose-900/60'
                }`}
              >
                <div>
                  <div className="flex items-start justify-between gap-2">
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase font-mono border ${
                      isLight
                        ? 'bg-rose-100 text-rose-800 border-rose-300'
                        : 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                    }`}>
                      {alert.type.replace(/_/g, ' ')}
                    </span>
                    <span className="text-[10px] text-slate-500 tabular-nums">
                      {alert.timestamp}
                    </span>
                  </div>

                  <div className={`text-xs font-bold mt-2 ${isLight ? 'text-slate-900' : 'text-white'}`}>
                    Principal: <span className={isLight ? 'text-rose-700' : 'text-rose-400'}>{alert.username}</span>
                  </div>

                  <div className={`text-[11px] mt-1 ${isLight ? 'text-slate-700' : 'text-slate-300'}`}>
                    Route: <code className={`px-1.5 py-0.5 rounded ${
                      isLight ? 'text-blue-700 bg-blue-50 border border-blue-200' : 'text-blue-400 bg-slate-900'
                    }`}>{alert.endpoint}</code>
                  </div>

                  <div className={`text-[11px] mt-1.5 line-clamp-2 ${isLight ? 'text-slate-600' : 'text-slate-400'}`}>
                    {alert.message}
                  </div>

                  <div className={`mt-2 text-[10px] px-2 py-1 rounded border flex items-center gap-1.5 ${
                    isLight
                      ? 'text-emerald-800 bg-emerald-50 border-emerald-200'
                      : 'text-emerald-400 bg-emerald-950/30 border-emerald-500/20'
                  }`}>
                    <ShieldCheck className={`w-3 h-3 shrink-0 ${isLight ? 'text-emerald-600' : 'text-emerald-400'}`} />
                    <span>Mitigation: {alert.mitigation}</span>
                  </div>
                </div>

                <div className={`mt-3 pt-2 border-t flex items-center justify-between gap-2 ${
                  isLight ? 'border-slate-200' : 'border-slate-900'
                }`}>
                  <div className="flex items-center gap-1.5">
                    {onQuarantineUser && (
                      <button
                        type="button"
                        onClick={() => onQuarantineUser(alert.username)}
                        className={`px-2 py-1 text-[10px] rounded border flex items-center gap-1 transition-colors ${
                          isLight
                            ? 'bg-rose-100 hover:bg-rose-200 text-rose-800 border-rose-300'
                            : 'bg-rose-900/50 hover:bg-rose-800 text-rose-200 border-rose-700/60'
                        }`}
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
                        className={`px-2 py-1 text-[10px] rounded border flex items-center gap-1 transition-colors ${
                          isLight
                            ? 'bg-blue-50 hover:bg-blue-100 text-blue-800 border-blue-200'
                            : 'bg-blue-900/50 hover:bg-blue-800 text-blue-200 border-blue-700/60'
                        }`}
                      >
                        Admin Cockpit
                      </button>
                    )}
                  </div>

                  <button
                    type="button"
                    onClick={() => onAcknowledgeAlert(alert.id)}
                    className={`px-2 py-1 text-[10px] rounded border flex items-center gap-1 transition-colors ${
                      isLight
                        ? 'bg-slate-100 hover:bg-slate-200 text-slate-800 border-slate-300'
                        : 'bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border-slate-700'
                    }`}
                  >
                    <CheckCircle className="w-3 h-3 text-emerald-500" />
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
