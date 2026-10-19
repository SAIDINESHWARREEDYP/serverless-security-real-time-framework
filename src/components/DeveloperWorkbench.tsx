import React, { useState } from 'react';
import {
  Code,
  Terminal,
  Play,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Cpu,
  Layers,
  Zap,
  Lock,
  Unlock,
  Shield,
  Bot,
  FileCode,
  ArrowRight,
  Sparkles
} from 'lucide-react';
import { motion } from 'motion/react';
import { AuthSession, FunctionRule, SecurityAuditLog } from '../types.ts';
import { AICloudThreatShield } from './AICloudThreatShield.tsx';

interface DeveloperWorkbenchProps {
  currentSession: AuthSession;
  rules: FunctionRule[];
  logs: SecurityAuditLog[];
  onFireFunction: (functionName: string) => Promise<void>;
  isFiring?: boolean;
  onOpenArchitecture?: () => void;
}

export const DeveloperWorkbench: React.FC<DeveloperWorkbenchProps> = ({
  currentSession,
  rules,
  logs,
  onFireFunction,
  isFiring = false,
  onOpenArchitecture
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'sandbox' | 'aiShield' | 'tokenInspector'>('sandbox');
  const [selectedEndpoint, setSelectedEndpoint] = useState<string>('viewSecurityLogs');
  const [lastResponse, setLastResponse] = useState<any | null>(null);
  const [executionTime, setExecutionTime] = useState<number | null>(null);
  const [isExecuting, setIsExecuting] = useState(false);

  // Filter logs to developer's events
  const developerLogs = logs.filter(
    (l) => l.username.toLowerCase() === currentSession.user.username.toLowerCase()
  );

  const developerEndpoints = [
    {
      name: 'getDashboardMetrics',
      tier: 'Tier 1 (Safe)',
      desc: 'Retrieves cluster health telemetry and operational statistics.',
      risk: 10,
      permitted: true
    },
    {
      name: 'viewSecurityLogs',
      tier: 'Tier 2 (Internal)',
      desc: 'Queries distributed security audit logs and sequence records.',
      risk: 25,
      permitted: true
    },
    {
      name: 'deployWorkerCode',
      tier: 'Tier 2 (Internal)',
      desc: 'Triggers edge V8 isolate serverless bundle deployment.',
      risk: 35,
      permitted: true
    },
    {
      name: 'updateSystemPolicy',
      tier: 'Tier 3 (Admin Restricted)',
      desc: 'Pushes dynamic Markov rules and risk thresholds. (Will be blocked)',
      risk: 80,
      permitted: false
    }
  ];

  const handleExecute = async (endpointToFire?: string) => {
    const target = endpointToFire || selectedEndpoint;
    setIsExecuting(true);
    const start = performance.now();
    try {
      await onFireFunction(target);
      const res = await fetch(`/api/${target}`, {
        headers: {
          Authorization: `Bearer ${currentSession.token}`
        }
      });
      const data = await res.json();
      setLastResponse(data);
    } catch (err: any) {
      setLastResponse({ error: err?.message || 'Invocation failed' });
    } finally {
      setExecutionTime(Math.round(performance.now() - start));
      setIsExecuting(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="space-y-6"
    >
      {/* Developer Header Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2.5 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400 shrink-0">
              <Code className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base sm:text-lg font-bold text-white tracking-tight">
                  Developer Cloud &amp; Edge Workbench
                </h2>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-blue-500/15 text-blue-300 border border-blue-500/30">
                  Tier 1 &amp; 2 Verified Clearance
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1 max-w-2xl">
                Integrated cloud microservices sandbox with edge isolate execution, state transition telemetry, and Next-Gen AI threat inspection.
              </p>
            </div>
          </div>

          {/* Sub-tab switcher */}
          <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs font-mono">
            <button
              onClick={() => setActiveSubTab('sandbox')}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                activeSubTab === 'sandbox'
                  ? 'bg-blue-600 text-white font-medium'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Cloud Sandbox
            </button>
            <button
              onClick={() => setActiveSubTab('aiShield')}
              className={`px-3 py-1.5 rounded-md flex items-center gap-1.5 transition-colors ${
                activeSubTab === 'aiShield'
                  ? 'bg-blue-600 text-white font-medium'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Bot className="w-3.5 h-3.5" />
              AI Threat Shield
            </button>
            <button
              onClick={() => setActiveSubTab('tokenInspector')}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                activeSubTab === 'tokenInspector'
                  ? 'bg-blue-600 text-white font-medium'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              JWT Session
            </button>
          </div>
        </div>
      </div>

      {/* VIEW 1: CLOUD SANDBOX */}
      {activeSubTab === 'sandbox' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Microservice Invocation & Sequence Playground */}
          <div className="lg:col-span-6 space-y-4">
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 font-mono text-xs">
              <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
                <span className="text-white font-bold flex items-center gap-2">
                  <Play className="w-4 h-4 text-blue-400" />
                  Edge Microservice Invocation
                </span>
                <span className="text-[10px] text-slate-500">Cloudflare Worker Simulator</span>
              </div>

              {/* Endpoint Selection Grid */}
              <div className="space-y-2 mb-4">
                {developerEndpoints.map((ep) => (
                  <button
                    key={ep.name}
                    onClick={() => setSelectedEndpoint(ep.name)}
                    className={`w-full p-3 rounded-lg border text-left transition-all flex items-center justify-between ${
                      selectedEndpoint === ep.name
                        ? 'bg-blue-950/40 border-blue-500/50 text-white shadow-sm'
                        : 'bg-slate-950/70 border-slate-800/80 text-slate-300 hover:border-slate-700 hover:text-white'
                    }`}
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <code className="text-xs font-bold">{ep.name}</code>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                          ep.permitted
                            ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                            : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                        }`}>
                          {ep.tier}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1">
                        {ep.desc}
                      </p>
                    </div>

                    <div className="text-right shrink-0 ml-3">
                      <span className="text-[10px] text-slate-500 block">Base Risk</span>
                      <span className="text-xs font-bold text-slate-300">{ep.risk}%</span>
                    </div>
                  </button>
                ))}
              </div>

              {/* Invocation Action Buttons */}
              <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
                <div className="text-[11px] text-slate-400">
                  Principal: <strong className="text-blue-300">{currentSession.user.username}</strong>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleExecute()}
                    disabled={isExecuting || isFiring}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-colors disabled:opacity-50 shadow-sm"
                  >
                    <Play className={`w-3.5 h-3.5 ${isExecuting ? 'animate-spin' : ''}`} />
                    <span>{isExecuting ? 'Dispatching...' : 'Dispatch Invocation'}</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Sequence Transition Architecture Guide */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 font-mono text-xs">
              <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-800">
                <span className="text-white font-semibold flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-indigo-400" />
                  Permitted Markov Transition Rules ({rules.length})
                </span>
                {onOpenArchitecture && (
                  <button
                    onClick={onOpenArchitecture}
                    className="text-[10px] text-blue-400 hover:underline"
                  >
                    View Cloud Blueprint →
                  </button>
                )}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                {rules.map((rule) => (
                  <div
                    key={rule.id}
                    className="p-2 rounded bg-slate-950 border border-slate-800/80 flex items-center justify-between text-[11px]"
                  >
                    <code className="text-blue-300 truncate">{rule.current_function}</code>
                    <ArrowRight className="w-3 h-3 text-slate-600 shrink-0 mx-1" />
                    <code className="text-emerald-300 truncate">{rule.allowed_next_function}</code>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Right Column: Execution Output & Response Telemetry */}
          <div className="lg:col-span-6 space-y-4">
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 font-mono text-xs shadow-sm">
              <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
                <span className="text-white font-bold flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-emerald-400" />
                  Live Execution Telemetry &amp; Payload
                </span>
                {executionTime !== null && (
                  <span className="text-[10px] font-mono text-slate-400">
                    Latency: <strong className="text-emerald-400">{executionTime}ms</strong>
                  </span>
                )}
              </div>

              {lastResponse ? (
                <div className="space-y-3">
                  <div className={`p-3 rounded-lg border text-xs flex items-center justify-between ${
                    lastResponse.status === 'BLOCKED' || lastResponse.error
                      ? 'bg-rose-950/30 border-rose-500/30 text-rose-300'
                      : 'bg-emerald-950/30 border-emerald-500/30 text-emerald-300'
                  }`}>
                    <div className="flex items-center gap-2">
                      {lastResponse.status === 'BLOCKED' || lastResponse.error ? (
                        <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                      ) : (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                      )}
                      <span>
                        Status:{' '}
                        <strong>
                          {lastResponse.status || (lastResponse.error ? 'ERROR' : 'HTTP 200 OK')}
                        </strong>
                      </span>
                    </div>
                    {lastResponse.calculated_risk !== undefined && (
                      <span className="text-[11px] font-mono">
                        Calculated Risk: <strong>{lastResponse.calculated_risk}%</strong>
                      </span>
                    )}
                  </div>

                  {lastResponse.reason && (
                    <div className="p-2.5 bg-slate-950 border border-slate-800 rounded text-slate-300 text-[11px]">
                      <strong className="text-slate-400 block mb-0.5">Interceptor Policy Decision:</strong>
                      {lastResponse.reason}
                    </div>
                  )}

                  <div>
                    <span className="text-slate-500 text-[10px] uppercase block mb-1">
                      Raw JSON Response
                    </span>
                    <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-slate-300 text-[11px] overflow-x-auto max-h-56">
                      {JSON.stringify(lastResponse, null, 2)}
                    </pre>
                  </div>
                </div>
              ) : (
                <div className="text-center py-14 text-slate-500">
                  <Terminal className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                  <p className="text-xs">Select a microservice endpoint on the left and click "Dispatch Invocation".</p>
                </div>
              )}
            </div>

            {/* My Developer Audit Logs */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 font-mono text-xs">
              <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-800">
                <span className="text-white font-semibold">
                  My Recent Invocations ({developerLogs.length})
                </span>
                <span className="text-[10px] text-slate-500">Filtered by {currentSession.user.username}</span>
              </div>

              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {developerLogs.length > 0 ? (
                  developerLogs.slice(0, 8).map((log) => (
                    <div
                      key={log.id}
                      className="p-2 rounded bg-slate-950 border border-slate-800/80 flex items-center justify-between text-[11px]"
                    >
                      <div className="flex items-center gap-2">
                        <span className={`w-1.5 h-1.5 rounded-full ${
                          log.status === 'ALLOWED' ? 'bg-emerald-400' : 'bg-rose-400'
                        }`} />
                        <code className="text-slate-300">{log.requested_function}</code>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500 text-[10px]">
                          Risk: {log.calculated_risk}%
                        </span>
                        <span className={`text-[10px] px-1 rounded ${
                          log.status === 'ALLOWED'
                            ? 'bg-emerald-500/10 text-emerald-400'
                            : 'bg-rose-500/10 text-rose-400'
                        }`}>
                          {log.status}
                        </span>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-center py-4 text-slate-500 text-xs">
                    No invocations logged for this session yet.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* VIEW 2: NEXT-GEN AI CLOUD THREAT SHIELD */}
      {activeSubTab === 'aiShield' && (
        <AICloudThreatShield
          currentUsername={currentSession.user.username}
          userRole={currentSession.user.role}
        />
      )}

      {/* VIEW 3: JWT TOKEN & SESSION INSPECTOR */}
      {activeSubTab === 'tokenInspector' && (
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 font-mono text-xs space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div>
              <h3 className="text-white font-bold">Cryptographic Session &amp; Claims Inspector</h3>
              <p className="text-slate-400 text-[11px]">RFC-7519 HMAC-SHA256 Token State</p>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
              Session Active
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg space-y-2">
              <span className="text-slate-400 text-[10px] uppercase font-bold">Decoded Payload Claims</span>
              <div className="space-y-1.5 text-[11px]">
                <div className="flex justify-between">
                  <span className="text-slate-500">sub (Username):</span>
                  <span className="text-blue-300 font-bold">{currentSession.user.username}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">role (Clearance):</span>
                  <span className="text-purple-300 font-bold">{currentSession.user.role}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">base_risk:</span>
                  <span className="text-amber-300 font-bold">{currentSession.user.base_risk_score}%</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">status:</span>
                  <span className="text-emerald-300 font-bold">{currentSession.user.status || 'APPROVED'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">amr (MFA Factor 2):</span>
                  <span className="text-cyan-300 font-bold">{currentSession.mfaMethod ? currentSession.mfaMethod.toUpperCase() : 'TOTP / SMS (VERIFIED)'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">issued_at:</span>
                  <span className="text-slate-300">{currentSession.loginTime}</span>
                </div>
              </div>
            </div>

            <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg space-y-2">
              <span className="text-slate-400 text-[10px] uppercase font-bold">Raw Bearer Header</span>
              <div className="bg-slate-900 p-2.5 rounded border border-slate-800 text-[11px] text-slate-300 break-all font-mono">
                <code>Authorization: Bearer {currentSession.token}</code>
              </div>
              <p className="text-[10px] text-slate-500">
                Validated at edge interceptors before Markov sequence analysis.
              </p>
            </div>
          </div>
        </div>
      )}
    </motion.div>
  );
};
